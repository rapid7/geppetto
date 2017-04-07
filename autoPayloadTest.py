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
    
def addHypervisors(hypervisorConfigs, vmList, logFile = None):
    for vmData in vmList:
        if 'HYPERVISOR_CONFIG' in vmData:
            if vmData['HYPERVISOR_CONFIG'] not in hypervisorConfigs:
                hypervisorConfigs.append(vmData['HYPERVISOR_CONFIG'])
                logMsg(logFile, "ADDED " + str(vmData['HYPERVISOR_CONFIG']))
            else:
                logMsg(logFile, str(vmData['HYPERVISOR_CONFIG']) + " IS NOT UNIQUE")
    
def bailSafely(testVmList, msfVms):
        for vm in  msfVms:
            vm.revertDevVm()
            vm.powerOff()
        for vm in testVmList:
            vm.revertToTestingBase()
            vm.powerOff()
        exit(1)

def createServer(configDic, logFile = "default.log"):
    if "HYPERVISOR_TYPE" not in configDic:
        print "INVALID CONFIG FILE; NO HYPERVISOR_TYPE FOUND"
        return None
    if configDic['HYPERVISOR_TYPE'].lower() == "esxi":
        return esxiVm.esxiServer(configDic, logFile)
    if configDic['HYPERVISOR_TYPE'].lower() == "workstation":
        return workstationVm.workstationServer(configDic, logFile)
    
def getUniqueHypervisorConfigs(configData):
    hypervisorConfigs = []
    if 'MSF_VMS' in configData:
        addHypervisors(hypervisorConfigs, configData['MSF_VMS'], configData['LOG_FILE'])
    if 'UPLOAD_TARGETS' in configData:
        addHypervisors(hypervisorConfigs, configData['UPLOAD_TARGETS'], configData['LOG_FILE'])
    if 'EXPLOIT_TARGETS' in configData:
        addHypervisors(hypervisorConfigs, configData['EXPLOIT_TARGETS'], configData['LOG_FILE'])
    return hypervisorConfigs

def getVmNames(configData):
    targetVmNames   = []
    msfVmNames      = []
    if 'MSF_VMS' in configData:
        for vm in configData['MSF_VMS']:
            msfVmNames.append(vm['NAME'])
    if 'UPLOAD_TARGETS' in configData:
        for target in configData['UPLOAD_TARGETS']:
            if 'HYPERVISOR_CONFIG' in target:
                targetVmNames.append(target['NAME'])
    if 'EXPLOIT_TARGETS' in configData:
        for target in configData['UPLOAD_TARGET']:
            if 'HYPERVISOR_CONFIG' in target:
                targetVmNames.append(target['NAME'])
    return (targetVmNames, msfVmNames)
    
def logMsg(logFile, strMsg):
	if strMsg == None:
		strMsg="[None]"
	dateStamp = 'testlog:[' + str(datetime.now())+ '] '
	#DELETE THIS LATER:
	print dateStamp + strMsg
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
    requiredList.append("MSF_VMS")
    requiredList.append("PAYLOAD_LIST")
    requiredList.append("COMMAND_LIST")
    requiredList.append("SUCCESS_LIST")
    for item in requiredList:
        if item not in jsonDic:
            print "MISSING " + item + " IN CONFIG: " + configFile
            configPassed = False
    if not configPassed:
        return None
    
    """
    MSF_VM_DATA
    """
    requiredMsfData = []
    requiredMsfData.append("HYPERVISOR_CONFIG")
    requiredMsfData.append("NAME")
    requiredMsfData.append("USERNAME")
    requiredMsfData.append("PASSWORD")
    for requiredData in requiredMsfData:
        for msfVm in jsonDic['MSF_VMS']:
            if requiredData not in  msfVm:
                print "NO " + requiredData + " LISTED FOR MSF_VM IN " + configFile
                configPassed = False
    if not configPassed:
        return None
    """
    SPECIFIC FOR UPLOAD_TARGETS
    """
    if 'UPLOAD_TARGETS' in jsonDic:
        #CHECK TO SEE IF WE ARE USING PYTHON AND/OR JAVA PAYLOADS
        for payload in jsonDic['PAYLOAD_LIST']:
            if 'java' in payload.lower():
                hasJavaPayload = True
            if 'python' in payload.lower():
                hasPythonPayload = True
        #VERIFY REQUIRED DATA IN UPLOAD_TARGET TYPES
        requiredTargetData = []
        requiredTargetData.append("HYPERVISOR_CONFIG")
        requiredTargetData.append("NAME")
        requiredTargetData.append("USERNAME")
        requiredTargetData.append("PASSWORD")
        requiredTargetData.append("PAYLOAD_DIRECTORY")
        if hasJavaPayload:
            requiredTargetData.append("JAVA_PATH")
        if hasPythonPayload:
            requiredTargetData.append("PYTHON_PATH")
        for uploadTarget in jsonDic['UPLOAD_TARGETS']:
            for requiredItem in requiredTargetData:
                if requiredItem not in uploadTarget:
                    print "NO " + requiredItem + " LISTED FOR " + uploadTarget['NAME'] + " IN " + configFile
                    configPassed = False
        if not configPassed:
            return None
    if 'EXPLOIT_TARGETS' in jsonDic:
        requiredExploitData = []
        requiredExploitData.append("NAME")
        requiredExploitData.append("IP_ADDRESS")
        requiredExploitData.append("EXPLOIT_MODULE")
        for exploitTarget in jsonDic['EXPLOIT_TARGETS']:
            for requiredItem in requiredExploitData:
                if requiredItem not in  exploitTarget:
                    print "NO " + requiredItem + " LISTED FOR " + exploitTarget['NAME'] + " IN " + configFile
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
    targetVms   = []
    msfVms      = []
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
    GET A LIST OF ALL THE HYPERVISORS WE NED TO USE FOR THE TEST
    """
    hypervisorConfigs = getUniqueHypervisorConfigs(configData)
    logMsg(configData['LOG_FILE'], "UNIQUE HYPERVISOR CONFIG FILES: " + str(hypervisorConfigs))
    hypervisorDic = {}
    for hypervisorConfig in hypervisorConfigs:
        hypervisorData = parseHypervisorConfig(hypervisorConfig)
        hypervisorDic[hypervisorConfig] = createServer(hypervisorData, configData['LOG_FILE'])
        if hypervisorDic[hypervisorConfig] == None:
            bailSafely(targetVms, msfVms)
        else:
            hypervisorDic[hypervisorConfig].enumerateVms()
    for hypervisor in hypervisorDic:
        logMsg(configData['LOG_FILE'], "VMS ON " + str(hypervisor))
        for vm in hypervisorDic[hypervisor].vmList:
            logMsg(configData['LOG_FILE'], str(vm.vmName))
        
    bailSafely(targetVms, msfVms)

    """
    GET A LIST OF ALL TEST VMS
    """
    targetVmNames, msfVmNames = getVmNames(configData)
    logMsg(configData['LOG_FILE'], "MSF VMS: " + str(msfVmNames))
    logMsg(configData['LOG_FILE'], "TARGET VMS: " + str(targetVmNames))
    
    """
    FIND THE VMS WE WANT TO USE
    """        
    for vm in 
    
    bailSafely(targetVms, msfVms)
    
    """
    PARSE THE HYPERVISOR CONFIG FILES AND INSTANTIATE THE HYPERVISOR OBJECTS
    """
    hypervisorObjData = {}
    for configFile in hypervisorConfigs:
        #PARSE THE CONFIG FILE
        hypervisorData = parseHypervisorConfig(configFile)
        # CREATE HYPERVISOR INSTANCE
        hypervisorInstance = createServer(hypervisorData)
        #CREATE THE HYPERVISOR OBJECT AND STORE IT IN A DICTIONARY WITH THE CONFIG FILENAME AS THE KEY
        if hyperVisorInstance != None:
            hypervisorObjData['configFile'] = hypervisorInstance
        else:
            logMsg(configData['LOG_FILE'], "FAILED TO CREATE HYPERVISOR INSTANCE FROM " + str(configFile))
            bailSafely(testVms, devVms)
        
    """
    ENUMERATE THE VMs ON THE HYPERVISORS AND TAG THE ONES USED IN THE TEST
    """
    if hyperVisorType == None:
        logMsg(logFile, "ERROR: NO HYPERVISOR_TYPE DEFINED IN CONFIG FILE")
        bailSafely(testVms, devVm)
    if hyperVisorType.lower() == 'workstation':
        try:
            vmrunExe =          testConfig['VMRUN_EXE_PATH']
            vmPath =            testConfig['VM_PATH']
            vmServer = workstationVm.workstationServer(vmrunExe, vmPath)
        except KeyError as e:
            logMsg(logFile, "FAILED TO LOAD INFRASTRUCTURE DATA:" + str(e))
            bailSafely(testVms, devVm)
    elif hyperVisorType.lower() == 'esxi':
        try:
            hypervisorHostname =    infrastructureConfig['HYPERVISOR_HOST']
            hyperVisorPassword =    infrastructureConfig['HYPERVISOR_PASSWORD']
            hyperVisorUsername =    infrastructureConfig['HYPERVISOR_USERNAME']
        except KeyError as e:
            logMsg(logFile, "FAILED TO LOAD INFRASTRUCTURE DATA:" + str(e))
            bailSafely(testVms, devVm)
        vmServer = esxiVm.esxiServer(	hypervisorHostname, 
										hyperVisorUsername, 
										hyperVisorPassword, 
										"443",
										testConfig['REPORT_DIR'] + "/server.log")
        if not vmServer.connect():
            logMsg(logFile, "[FATAL ERROR]: FAILED TO CONNECT TO " + hypervisorHostname)
            bailSafely(testVms, devVm)
    else:
        logMsg(logFile, "UNKNOWN hyperVisor TYPE: " + str(hyperVisorType))
        exit
    
    """
    SET THE DEV AND TEST VMS
    """
    vmServer.enumerateVms()
    devVmList   =   apt_shared.findAndConfigVms(vmServer.vmList, [devVmData])
    testVms   =     apt_shared.findAndConfigVms(vmServer.vmList, vmUploadTargets)
    if len(devVmList) != 1:
        logMsg(logFile, "[FATAL ERROR]: COULD NOT PARSE DEV_VM_DATA IN " + testJsonFile)
        bailSafely(testVms, devVm)
    if len(testVms) != len(vmUploadTargets):
        logMsg(logFile, "[WARNING]: SOME TEST VM DATA DID NOT PARSE CORRECTLY!")
        logMsg(logFile, "FOUND " + str(len(testVms)) + " TEST VMS")
        logMsg(logFile, "FOUND " + str(len(vmUploadTargets)) + " TEST VMS")
    if len(testVms) == 0:
        logMsg(logFile, "[FATAL ERROR]: COULD NOT PARSE TEST_VM_DATA IN " + testJsonFile)
        bailSafely(testVms, devVm)
    devVm = devVmList[0]
    print testVms
    logMsg(logFile, "USING DEV VM: " + devVm.vmName)
    logMsg(logFile, "FOUND " + str(len(testVms)) + " TEST VMS")

    """
    REVERT TEST VMS TO TESTING_BASE
    SNAPSHOT DEV VM
    START ALL THE VMS
    """
    usedVmList = testVms[:]
    usedVmList.append(devVm)
    devVm.takeTempSnapshot()
    for vm in testVms:
        vm.revertToTestingBase()
    for vm in usedVmList:
        vm.prepVm()
    
    """
    WAIT FOR THE VMS TO BE READY
    """
    if not vmServer.waitForVmsToBoot(usedVmList):
        logMsg(logFile, "ERROR: ONE OR MORE VMS FAILED TO INITIALIZE; EXITING")
        bailSafely(testVms, devVm)
    """
    CREATE REQUIRED DIRECTORY
    """
    for vm in testVms:
        if 'windows' in vm.vmOS.lower():
            vm.makeDirOnGuest(testConfig['WIN_PAYLOAD_DIRECTORY'])
        else:
            vm.makeDirOnGuest(testConfig['NIX_PAYLOAD_DIRECTORY'])
    
    """
    GENERATE LIST OF ALL VMS + APPLICABLE PAYLOADS FOR THAT VM
    """
    msfPath = "/home/" + devVm.getUsername() + "/rapid7/metasploit-framework/"
    localScriptName =    testConfig['SCRIPT_DIR'] + "/" + payloadCreationScript
    remoteScriptName = msfPath + payloadCreationScript
    for i in testVms:
        for j in payloadTypeList:
            if not (('x86' in i.getArch()) and ('x64' in j.lower())):
                i.payloadList.append(apt_shared.makeMetCmd(j, 
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
    
