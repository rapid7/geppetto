import sys
sys.path.insert(0, '../vm-automation')

import workstationVm
import apt_shared
import esxiVm
from datetime import datetime

import time
import hashlib
import os
import json
    
def bailSafely(targets, msfHosts):
        for host in  msfHosts:
            if host['METHOD'] == "VM_TOOLS":
                host['VM_OBJECT'].revertMsfVm()
                host['VM_OBJECT'].powerOff()
        for host in  targets:
            if host['METHOD'] == "VM_TOOLS":
                host['VM_OBJECT'].revertToTestingBase()
                host['VM_OBJECT'].powerOff()
        exit(1)

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
        print "INVALID CONFIG FILE; NO HYPERVISOR_TYPE FOUND"
        return None
    if hypervisorDic['HYPERVISOR_TYPE'].lower() == "esxi":
        return esxiVm.esxiServer(hypervisorDic, logFile)
    if hypervisorDic['HYPERVISOR_TYPE'].lower() == "workstation":
        return workstationVm.workstationServer(hypervisorDic, logFile)
        
def instantiateVmsAndServers(machineList, hypervisorDic, logFile):
    for target in machineList:
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
            for vm in target['SERVER_OBJECT'].vmList:
                if vm.vmName == target['NAME']:
                    logMsg(logFile, "FOUND VM: " + vm.vmName)
                    target['VM_OBJECT'] = vm
                    vm.setPassword(target['PASSWORD'])
                    vm.setUsername(target['USERNAME'])
    return None

def logMsg(logFile, strMsg):
	if strMsg == None:
		strMsg="[None]"
	dateStamp = 'testlog:[' + str(datetime.now())+ '] '
	#DELETE THIS LATER:
	print dateStamp + str(strMsg)
	try:
		logFileObj = open(logFile, 'ab')
		logFileObj.write(dateStamp + strMsg +'\n')
		logFileObj.close()
	except IOError:
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
        print "FAILED TO OPEN: " + configFile + '\n' + str(e)
        return None
    try:
        jsonDic = json.loads(jsonString)
    except Exception as e:
        print "FAILED TO PARSE DATA FROM: " + configFile + '\n' + str(e)
        return None
    """
    CHECK MAIN LEVEL FOR REQUIRED DATA
    """
    configPassed = True
    requiredList = []
    requiredList.append("TEST_NAME")
    requiredList.append("REPORT_PREFIX")
    requiredList.append("PAYLOAD_CREATION_SCRIPT")
    requiredList.append("BIND_SCRIPT")
    requiredList.append("TARGET_SCRIPT")
    requiredList.append("HTTP_PORT")
    requiredList.append("STARTING_LISTENER")
    requiredList.append("MSF_HOSTS")
    requiredList.append("TARGETS")
    requiredList.append("PAYLOADS")
    requiredList.append("COMMAND_LIST")
    requiredList.append("SUCCESS_LIST")
    for item in requiredList:
        if item not in jsonDic:
            print "MISSING " + item + " IN CONFIG: " + configFile
            configPassed = False
    if not configPassed:
        return None
    
    """
    MSF_HOSTS
    """
    requiredMsfData = []
    requiredMsfData.append("TYPE")
    requiredMsfData.append("METHOD")
    requiredMsfData.append("NAME")
    requiredMsfData.append("USERNAME")
    requiredMsfData.append("PASSWORD")
    for requiredData in requiredMsfData:
        for msfHost in jsonDic['MSF_HOSTS']:
            if requiredData not in  msfHost:
                print "NO " + requiredData + " LISTED FOR MSF_HOST IN " + configFile
                configPassed = False
    if not configPassed:
        return None
    """
    SPECIFIC FOR TARGETS
    """
    for target in jsonDic['TARGETS']:
        requiredTargetData = []
        requiredTargetData.append("TYPE")
        requiredTargetData.append("NAME")
        if target['METHOD'] == 'EXPLOIT':
            requiredTargetData.append("NAME")
            requiredTargetData.append("IP_ADDRESS")
            requiredTargetData.append("EXPLOIT_MODULE")
            requiredTargetData.append("EXPLOIT_SETTINGS")
        if target['METHOD'] == "VM_TOOLS":
            requiredTargetData.append("HYPERVISOR_CONFIG")
            requiredTargetData.append("USERNAME")
            requiredTargetData.append("PASSWORD")
            requiredTargetData.append("PAYLOAD_DIRECTORY")
            for payload in jsonDic['PAYLOADS']:
                if 'java' in payload['NAME'].lower():
                    hasJavaPayload = True
                    break
                if 'python' in payload['NAME'].lower():
                    hasPythonPayload = True
                    break
            if hasJavaPayload:
                requiredTargetData.append("JAVA_PATH")
            if hasPythonPayload:
                requiredTargetData.append("PYTHON_PATH")
        for requiredItem in requiredTargetData:
            if requiredItem not in target:
                print "NO " + requiredItem + " LISTED FOR " + target['NAME'] + " IN " + configFile
                configPassed = False
        if not configPassed:
            return None
    return jsonDic

def parseHypervisorConfig(hypervisorConfigFile):
    try:
        fileObj = open(hypervisorConfigFile, 'r')
        jsonString = fileObj.read()
        fileObj.close()
    except IOError as e:
        print "FAILED TO FIND HYPERVISOR CONFIG FILE: " + hypervisorConfigFile
        return None
    try:
        hypervisorData = json.loads(jsonString)
    except Exception as e:
        print "FAILED TO PARSE HYPERVISOR CONFIG FILE: " + str(e)
        return None
    return hypervisorData
                    
def main():
    targets     = []
    msfHosts    = []
    usageStatement = "autoPayloadTest <test.json>"
    if len(sys.argv) != 2:
        print "INCORRECT PARAMETER LIST:\n " + usageStatement
        bailSafely(testVms, msfVms)

    testJsonFile =              sys.argv[1]
    configData = parseTestConfig(testJsonFile)
    if None == configData:
        print "THERE WAS A PROBLEM WITH THE TEST JSON CONFIG FILE"
        bailSafely(testVms, msfVms)
    
    """
    SET UP DIRECTORIES
    """
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

    """
    UNIQUE, SEQUENTIAL PORT NUMBERS FOR LISTENING/CALLBACK ARE GENERATED
    BY A SINGLETON-TYPE CLASS MONSTROSITY; PREP IT
    """
    portNum = apt_shared.portValue(configData['STARTING_LISTENER'])

    """
    INSTANTIATE REQUIRED SERVER INSTANCES AND ADD THEM TO THE DICTIONARY
    THIS IS A LITTEL CLUDGY, BUT I HAVE PLANS AND THIS WILLMAKE EXTENDING 
    A LITTLE EASIER LATER WHEN WE ADD EXTRA VM GROUPS
    """
    hypervisors = {}
    instantiateVmsAndServers(configData['MSF_HOSTS']+configData['TARGETS'], hypervisors, configData['LOG_FILE'])

    """
    PREP ALL MSF_HOSTS AND TARGETS
    """
    #VMS
    for host in configData['TARGETS']:
        if host['TYPE'] == "VIRTUAL":
            host['VM_OBJECT'].revertToTestingBase()
    for host in configData['TARGETS'] + configData['MSF_HOSTS']:
        if host['TYPE'] == "VIRTUAL":
            host['VM_OBJECT'].prepVm()
    """
    WAIT FOR THE VMS TO BE READY
    """
    for config in hypervisors:
        vmsToCheck = []
        for host in configData['TARGETS'] + configData['MSF_HOSTS']:
            if host['TYPE'] == 'VIRTUAL':
                if host['SERVER_OBJECT'] == hypervisors[config]:
                    vmsToCheck.append(host['VM_OBJECT'])
        if not hypervisors[config].waitForVmsToBoot(vmsToCheck):
            logMsg(configData['LOG_FILE'], "ERROR: ONE OR MORE VMS FAILED TO INITIALIZE; EXITING")
            bailSafely(configData['TARGETS'], configData['MSF_HOSTS'])
    """
    CREATE REQUIRED DIRECTORY FOR PAYLOADS ON VM_TOOLS MANAGED MACHINES
    """
    for host in configData['TARGETS']:
        if host['METHOD'] == "VM_TOOLS":
            host['VM_OBJECT'].makeDirOnGuest(host['PAYLOAD_DIRECTORY'])
    
    """
    IF GLOBAL PAYLOADS ARE LISTED ADD THEM TO THE SPECIFIC PAYLOADS, IF THEY EXIST
    """
    if "PAYLOADS" in configData:
        for target in configData['TARGETS']:
            if 'PAYLOADS' not in target:
                target['PAYLOADS'] = []
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
                target['PAYLOADS'].append(payload)
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "PAYLOADS FOR " + target['NAME'])
        for payload in target['PAYLOADS']:
            logMsg(configData['LOG_FILE'], payload['NAME'])
    bailSafely(configData['TARGETS'], configData['MSF_HOSTS'])
            
                    
                    
                    
                    
                    
                    
    """                    
                    (apt_shared.makeMetCmd(j, 
                                                               devVm.getVmIp(), 
                                                               i.getVmIp(), 
                                                               str(portNum.get()), 
                                                               cmdList))
        
        remoteCommitFile = msfPath + "commit_tag_" + testConfig['TIMESTAMP']
        apt_shared.makeDevPayloadScript(devVm.getVmIp(), 
                                        msfPath, 
                                        testVms, 
                                        httpPort, 
                                        localScriptName,
                                        remoteCommitFile)
    """
    """
    UPLOAD AND RUN THE PAYLOAD GENERATOR/REVERSE HANDLER SCRIPT
    """
    if not devVm.uploadFileToGuest(localScriptName, remoteScriptName):
        logMsg(logFile, "[FATAL ERROR]: FAILED TO UPLOAD PAYLOAD CREATION SCRIPT TO " + devVm.vmName)
        bailSafely(testVms, devVm)
    chmodCmdList = "/bin/chmod 755".split() + [remoteScriptName]
    if not devVm.runCmdOnGuest(chmodCmdList):
        logMsg(logFile, "[FATAL ERROR]: FAILED RUN " + ' '.join(chmodCmdList) + " ON " + devVm.vmName)
        bailSafely(testVms, devVm)
    if not devVm.runCmdOnGuest([remoteScriptName]):
        logMsg(logFile, "[FATAL ERROR]: FAILED RUN " + remoteScriptName + " ON " + devVm.vmName)
        bailSafely(testVms, devVm)
    
    """
    WAIT FOR THE SCRIPT TO FINISH....
    """
    logMsg(logFile, "WAITING FOR PAYLOADS TO GENERATE...")
    pollingGap = 1
    pollingTimes = 1200
    try:
        for i in range(pollingTimes):
            time.sleep(pollingGap)
            devVm.updateProcList()
            procStr = ' '.join(devVm.procList)
            if payloadCreationScript not in procStr:
                logMsg(logFile, "PAYLOAD CREATION SCRIPT FINISHED")
                break
            else:
                if i%20 == 0:
                    logMsg(logFile, "PAYLOAD CREATION SCRIPT STILL RUNNING")
    except KeyboardInterrupt:
        print "CAUGHT KEYBOARD INTERRUPT; SKIPPING WAIT...."
    

    """
    MAKE PYTHON AND/OR BASH(ISH) SCRIPTS FOR TARGET MACHINES TO START PAYLOADS
    """
    remoteInterpreter =     None
    for vm in testVms:
        if 'windows' in vm.vmOS.lower():
            remoteScriptName =  testConfig['WIN_PAYLOAD_DIRECTORY'] + "\\" + testVmScriptName + ".py"
            localScriptName =   testConfig['SCRIPT_DIR'] + "/" + testConfig['TEST_SCRIPT'] + ".py"
            remoteInterpreter = testConfig['PYTHON_PATH']
        else:
            remoteScriptName =  testConfig['NIX_PAYLOAD_DIRECTORY'] + "/" + testVmScriptName + ".sh"
            localScriptName =   testConfig['SCRIPT_DIR'] + "/" + testConfig['TEST_SCRIPT'] + ".sh"
            remoteInterpreter = None
        apt_shared.makeShTestVmScript(devVm.getVmIp(), 
                                      msfPath, 
                                      vm, 
                                      localScriptName, 
                                      testConfig)
        if not vm.uploadAndRun(localScriptName, remoteScriptName, remoteInterpreter):
            logMsg(logFile, "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " ON " + vm.vmName)
            bailSafely(testVms, devVm)
    sleepTime = 15
    sleepGap = 7
    for i in payloadTypeList:
        if 'reverse' in i.lower():
            sleepTime = sleepTime + sleepGap
    logMsg(logFile, "WAITING " + str(sleepTime) + " SECONDS FOR BIND PAYLOAD LISTENERS TO LAUNCH")
    time.sleep(sleepTime)

    
    """
    MAKE BASH SCRIPT TO RUN BIND HANDLERS ON THE DEV VM
    """
    localScriptName = testConfig['SCRIPT_DIR'] + "/" + bindLaunchScript
    remoteScriptName = msfPath + bindLaunchScript
    apt_shared.makeBindLaunchScript(devVm.vmIp, msfPath, testVms, httpPort, localScriptName)
    if not devVm.uploadAndRun(localScriptName, remoteScriptName):
        logMsg(logFile, "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " TO " + devVm)
        bailSafely(testVms, devVm)
    
    """
    WAIT FOR THE msfconsole PROCESSES TO FINISH
    """
    logMsg(logFile, "WAITING FOR METERPRETER PROCESSES TO FINISH")
    pollingGap = 10
    pollingTimes = 10 + (len(testVms) * len(payloadTypeList))
    try:
        for i in range(pollingTimes):
            msfconsoleCount = 0
            time.sleep(pollingGap)
            devVm.updateProcList()
            for j in devVm.procList:
                if 'msfconsole' in j.lower():
                    logMsg(logFile, j)
                    msfconsoleCount = msfconsoleCount + 1
            msgOut = str(msfconsoleCount) + \
                     " msfconsole PROCESSES RUNNING; ABORTING IN " + \
                     str(pollingGap * (pollingTimes - i)) + " SECONDS."
            logMsg(logFile, msgOut)
            if 0 == msfconsoleCount:
                break
    except KeyboardInterrupt:
        print "CAUGHT KEYBOARD INTERRUPT; SKIPPING WAIT...."

    """
    PULL REPORT FILES FROM EACH TEST VM
    """
    logMsg(logFile, "GETTING REPORT FILES FROM VMS")
    reportFiles = []
    for i in testVms:
        for j in i.payloadList:
            srcFile = msfPath + "/" + j.rcScriptName + ".out"
            dstFile = testConfig['SESSION_DIR'] + "/" + j.rcScriptName + ".out"
            devVm.getFileFromGuest(srcFile, dstFile)
            reportFiles.append(dstFile)
    logMsg(logFile, "FINISHED DOWNLOADING VM REPORTS")
    
    """
    GET COMMIT VERSION
    """
    srcFile = remoteCommitFile
    dstFile = testConfig['REPORT_DIR'] + "/commit_" + testConfig['TIMESTAMP'] + ".txt"
    devVm.getFileFromGuest(srcFile, dstFile)
    try:
        fileObj = open(dstFile, 'r')
        commitRaw = fileObj.read().strip()
        fileObj.close()
    except IOError as e:
        logMsg(logFile, "FAILED TO OPEN " + dstFile)
        logMsg(logFile, "SYSTEM ERROR: \n" + str(e))
    else:
        commitVersion = commitRaw.split(' ')[1]
        logMsg(logFile, "COMMIT VERSION OF metasploit-framework: " + commitVersion)
    
    """
    RETURN ALL TESTING VMS TO TESTING_BASE
    RETURN DEV VM TO WHERE WE FOUND IT
    POWER OFF ALL VMS
    """
    devVm.revertDevVm()
    devVm.powerOff()
    for i in testVms:
        i.revertToTestingBase()
        i.powerOff()

    """
    COALLATE DATA
    """
    resultDict = apt_shared.populateResults(reportFiles, testVms, testConfig)

    """
    GENERATING REPORT
    """
    logMsg(logFile, "GENERATING MAIN REPORT")
    reportFileName = testConfig['REPORT_DIR'] + "/" + reportPrefix
    with open(reportFileName + ".json", 'wb') as jsonFile:
        json.dump(resultDict, jsonFile) 
    reportFile = apt_shared.generateReport(reportFiles, testVms, reportFileName + ".txt", testConfig['SESSION_DIR'], commitVersion)
    logMsg(logFile, "REPORT GENERATION COMPLETE, REPORT FILE: " + reportFile)
    apt_shared.makeWebResults(testVms, reportFileName + ".old.html")
    if not apt_shared.generateHtmlReport(resultDict, reportFileName + ".html", testVms, commitVersion, testConfig):
        logMsg(logFile, "FAILED TO GENERATE HTML REPORT")
    else:
        logMsg(logFile, "HTML REPORT AVAILABLE HERE: " + reportFileName + ".html")

    logMsg(logFile, "WAITING FOR ALL TASKS TO COMPLETE")
    time.sleep(5)
    logMsg(logFile, "EXIT")
    
if __name__ == "__main__":
    main()
    
