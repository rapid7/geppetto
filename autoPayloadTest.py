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
     
    #portValue TRACKS PORTS SO WE DO NOT REUSE A PORT AND CAUSE A PROBLEM
    portNum = apt_shared.portValue(configData['STARTING_LISTENER'])
    #REPLACE 'UNIQUE_PORT' WILDCARD WITH AN ACTUAL UNIQUE PORT
    apt_shared.replacePortKeywords(configData, portNum)
    
    #DEBUG PRINT
    for target in configData['TARGETS']:
        if 'PAYLOADS' in target:
            apt_shared.logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
        apt_shared.logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))

    """
    NOW EACH HOST HAS A LIST OF ALL THE MODULES AND (POSSIBLY) PAYLOADS IT NEEDS TO USE...... 
    ASSEMBLE EXPLOITS AND PAYLOADS OR JUST MODULES THEM TO FORM VOLTRON..... I MEAN, SESSION_DATA
    TO HELP TRACK THE ACTUAL SESSIONS ESTABLISHED (IF ANY)
    """
    apt_shared.setupSessionData(configData)
    
    #DEBUG PRINT
    apt_shared.logTargetData(configData)
            
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
            
    
    #DEBUG PRINT
    apt_shared.logTargetData(configData)
    
    """
    NOW THAT THE COMPLETE TEST CONFIG HAS BEEN CREATED, VERIFY IT
    """
    if not apt_shared.verifyConfig(configData):
        apt_shared.bailSafely(configData)

    """
    WHEN WE BREAK THIS APART, THIS IS THE LINE OF DEMARCATION FOR PICKLING
    SPLIT CONFIG INTO SMALLER CONFIGS HERE, THEN PARSE OUT THE REST.
    """
    
    testResult = apt_shared.runTest(configData, portNum)

    """
    RETURN VMS TO SNAPSHOTS
    """
    if resetVms(testConfig):
        apt_shared.logMsg(logFile, "SUCCESSFULLY RESET VMS")
    else:
        apt_shared.logMsg(logFile, "THERE WAS A PROBLEM RESETTING VMS")
    
    """
    WAIT A COUPLE SECONDS TO MAKE SURE WVERYTHING COMPLETES, THEN RETURN THE PROPER VALUE
    """
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
        exit(998)
    
if __name__ == "__main__":
    main()
    
