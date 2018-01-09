import apt_shared
import argparse
from datetime import datetime
import hashlib
import json
import os
import sys
import time
import vm_automation

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

    configData = apt_shared.prepConfig(args)

    """
    IF GLOBAL PAYLOADS OR MODULES ARE LISTED, FILTER THEM AS BEST WE CAN AND ADD THEM TO EACH TARGET
    NB: I THINK USING GLOBAL EXPLOITS IS A TERRIBLE IDEA, BUT I AM AN ENABLER
    """
    apt_shared.expandPayloadsAndModules(configData)

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
    NOW THAT THE MODULES AND PAYLOADS HAVE BEEN BROKEN OUT, REPLACE THE UNIQUE_PORT
    KEYWORDS WITH A UNIQUE PORT VALUE
    I WANTED TO AVOID PORT COLLISIONS, SO I MADE A CLASS THAT TRACKS THE PORTS AND 
    EACH TIME YOU RUN get() ON IT, IT RETURNS A PORT VALUE AND INCREMENTS IT SO
    AS LONG AS YOU GET PORTS FROM THIS STRUCT, THEY WILL NEVER COLLIDE.
    IT IS AS CLOSE AS I SEEM TO BE ABLE TO GET IN PYTHON TO A SINGLETON
    """
    portNum = apt_shared.portValue(configData['STARTING_LISTENER'])
    
    apt_shared.replacePortKeywords(configData, portNum)
    
    #DEBUG PRINT
    for target in configData['TARGETS']:
        if 'PAYLOADS' in target:
            apt_shared.logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
        apt_shared.logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))

    """
    NOW EACH HOST HAS A LIST OF ALL THE MODULES AND (POSSIBLY) PAYLOADS IT NEEDS TO USE...... 
    ASSEMBLE EXPLOITS AND PAYLOADS OR JUST MODULES THEM TO FORM VOLTRON..... I MEAN, SESSION_DATA
    TP HELP TRACK THE ACTUAL SESSION ESTABLISHED (IF ANY)
    """
    apt_shared.setupSessionData(configData)
    
    """
    JUST A DEBUG PRINT HERE TO VERIFY THE STRUCTURES WERE CREATED CORRECTLY
    """
    for target in configData['TARGETS']:
        apt_shared.logMsg(configData['LOG_FILE'], "================================================================================")
        apt_shared.logMsg(configData['LOG_FILE'], "SESSION_DATASETS FOR " + target['NAME'])
        apt_shared.logMsg(configData['LOG_FILE'], "================================================================================")
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                apt_shared.logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'] + ":" + sessionData['PAYLOAD']['NAME'])
            else:
                apt_shared.logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'])
            
    """
    PROCESS CLONES
    NOW THAT THE PAYLOAD AND EXPLOIT DATA IS NEATLY PLACED INTO THE SESSION_DATASETS LIST, WHEN WE PROCESS CLONES,
    ALL WE NEED TO DO IS COPY THE EXISTING DATA OVER EXCEPT THE HYPERVISOR CONFIGS AND THE SESSION_DATASETS
    HYPERVISOR CONFIGS REMAIN INDIVIDUAL AND SESSION_DATASETS ARE SPLIT AMONG THE TARGET CLONES
    """
    apt_shared.breakoutClones(configData['MSF_HOSTS'], configData['LOG_FILE'])
    apt_shared.breakoutClones(configData['TARGETS'], configData['LOG_FILE'])
    
    """
    EXPAND COMMAND_LIST AND SUCCESS_LIST TO ALL TARGETS
    """
    apt_shared.expandGlobalList(configData['TARGETS'], configData['COMMAND_LIST'], "COMMAND_LIST")
    apt_shared.expandGlobalList(configData['TARGETS'], configData['SUCCESS_LIST'], "SUCCESS_LIST")
            
    
    """
    JUST A DEBUG PRINT HERE TO VERIFY THE STRUCTURES WERE CREATED CORRECTLY
    """
    for target in configData['TARGETS']:
        apt_shared.logMsg(configData['LOG_FILE'], "================================================================================")
        apt_shared.logMsg(configData['LOG_FILE'], "SESSION_DATASETS FOR " + target['NAME'])
        apt_shared.logMsg(configData['LOG_FILE'], "================================================================================")
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                apt_shared.logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'] + ":" + sessionData['PAYLOAD']['NAME'])
            else:
                apt_shared.logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'])
    
    """
    NOW THAT THE COMPLETE TEST CONFIG HAS BEEN CREATED, VERIFY IT
    """
    if not apt_shared.verifyConfig(configData):
        apt_shared.bailSafely(configData)

    """
    WHEN WE BREAK THIS APART, THIS IS THE LINE OF DEMARCATION FOR PICKLING
    SPLIT CONFIG INTO SMALLER CONFIGS HERE, THEN PARSE OUT THE REST.
    """
    
    """
    FIGURE OUT HOW MANY PAYLOADS WE HAVE AND HOW MANY MSF_HOSTS WE HAVE
    SO WE CAN SPLIT THE WORK AMONG ALL MSF_HOSTS
    """
    msfHostCount = len(configData['MSF_HOSTS'])
    sessionCount = apt_shared.getSessionCount(configData)
    apt_shared.logMsg(configData['LOG_FILE'], "MSF_HOST COUNT = " + str(msfHostCount))
    apt_shared.logMsg(configData['LOG_FILE'], "SESSION COUNT = " + str(sessionCount))

    testVms = apt_shared.instantiateVmsAndServers(configData)
    # IF WE COULD NOT FIND A VM, ABORT
    if None in testVms:
        apt_shared.bailSafely(configData)

    #TAKE SNAPSHOT AND/OR SET THE VMS TO THE DESIRED SNAPSHOT AND POWERS ON
    apt_shared.prepTestVms(configData)
    
    # WAIT UNTIL ALL VMS HAVE A WORKING TOOLS SERVICE AND AN IP ADDRESS
    if False == apt_shared.waitForVms(testVms):
        apt_shared.bailSafely(testVms)
        
    # MAKE SURE THE TEST CONFIG HAS ANY DHCP ADDRESSES SET PROPERLY AND VERIFY ALL TARGETS?MSF_HOSTS HAVE AN IP
    if not apt_shared.setVmIPs(configData):
        apt_shared.bailSafely(testVms)

    msfHostCount = len(configData['MSF_HOSTS'])
    sessionCount = apt_shared.getSessionCount(configData)
    
    """
    CREATE REQUIRED DIRECTORY FOR PAYLOADS ON VM_TOOLS MANAGED MACHINES
    CAN'T DO THIS EARLIER, AS THE MACHINES WERE OFF AND WER NEEDED DHCP-Generated IP ADDRESSES
    """
    for host in configData['TARGETS']:
        if "VM_TOOLS_UPLOAD" in host['METHOD'].upper():
            host['VM_OBJECT'].makeDirOnGuest(host['PAYLOAD_DIRECTORY'])
            
    sessionCounter = apt_shared.prepStagedScripts(configData, portNum)
    
    apt_shared.finishAndLaunchStageOne(configData['MSF_HOSTS'], configData['HTTP_PORT'])
    
    if not apt_shared.waitForHttpServer(configData['MSF_HOSTS'], configData['LOG_FILE'], configData['HTTP_PORT']):
        apt_shared.bailSafely(testVms)
    
    if not apt_shared.waitForMsfPayloads(configData['MSF_HOSTS'], configData['REPORT_DIR'], configData['LOG_FILE']):
        apt_shared.bailSafely(testVms)      


    """
    STAGE TWO STUFF
    """
    
    terminationToken = "!!! STAGE TWO COMPLETE !!!"
    stageTwoResults = apt_shared.launchStageTwo(configData, terminationToken, 180)
    if not stageTwoResults[0]:
        apt_shared.bailSafely(testVms)
    else:
        stageTwoNeeded = stageTwoResults[1]
        stageThreeNeeded = stageTwoResults[1]
    
    """
    IF WE LAUNCHED STAGE TWO, WAIT FOR THE SCRIPTS TO COMPLETE
    """
    if stageTwoNeeded:
        if not apt_shared.finishStageTwo(configData, terminationToken):
            apt_shared(bailSafely)
    else:
        apt_shared.logMsg(configData['LOG_FILE'], "NO STAGE TWO REQUIRED")


    """
    MAKE STAGE THREE SCRIPT TO RUN BIND HANDLERS ON MSF HOSTS
    """
    if stageThreeNeeded:
        if not apt_shared.launchStageThree(configData):
            apt_shared.bailSafely(testVms)
        else:
            apt_shared.logMsg(configData['LOG_FILE'], "WAITING FOR MSFCONSOLES TO LAUNCH...")
            time.sleep(20)
    else:
        apt_shared.logMsg(configData['LOG_FILE'], "NO STAGE THREE SCRIPTS NEEDED")
        
    """
    WAIT FOR THE METERPRETER SESSIONS TO FINISH....
    """
    apt_shared.waitForMeterpreters(configData, sessionCounter)

    """
    PULL STAGE THREE LOG FILES FROM MSF VMS
    """
    if stageThreeNeeded:
        for msfHost in configData['MSF_HOSTS']:
            remoteFileName = msfHost['STAGE_THREE_LOGFILE']
            localFileName = configData['REPORT_DIR'] + '/' + msfHost['NAME'] + "_stageThreeLog.txt"
            msfHost['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName)
    else:
        apt_shared.logMsg(configData['LOG_FILE'], "NO STAGE THREE LOGFILES")
        
    """
    PULL REPORT FILES FROM EACH TEST VM
    """
    apt_shared.pullTargetLogs(configData)

    apt_shared.logMsg(configData['LOG_FILE'], "FINISHED DOWNLOADING REPORTS")
    
    """
    GET COMMIT VERSION AND PCAPS
    """
    apt_shared.pullMsfLogs(configData)
    
    """
    CHECK TEST RESULTS
    """
    
    testResult = apt_shared.checkData(configData)
    
    """
    GENERATE HTML REPORT
    """

    htmlReportString = apt_shared.makeHtmlReport(configData['TARGETS'], configData['MSF_HOSTS'])
    htmlFileName = configData['REPORT_DIR'] + "/" + configData['REPORT_PREFIX'] + ".html"
    try:
        fileObj = open(htmlFileName, 'w')
        fileObj.write(htmlReportString)
        fileObj.close()
    except IOError as e:
        apt_shared.logMsg(logFile, "FAILED TO OPEN " + htmlFileName)
        apt_shared.logMsg(logFile, "SYSTEM ERROR: \n" + str(e))

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
            apt_shared.logMsg(configData['LOG_FILE'], "REVERTING " + target['NAME'])
            target['VM_OBJECT'].revertToTestingBase()
            target['VM_OBJECT'].powerOff()

    apt_shared.logMsg(configData['LOG_FILE'], "WAITING FOR ALL TASKS TO COMPLETE")
    time.sleep(5)
    if testResult:
        apt_shared.logMsg(configData['LOG_FILE'], "TEST SUCCEEDED")
        if args.verbose:
            print("PASSED")
        exit(0)
    else:
        apt_shared.logMsg(configData['LOG_FILE'], "TEST FAILED")
        if args.verbose:
            print("FAILED")
        exit(999)
    
if __name__ == "__main__":
    main()
    
