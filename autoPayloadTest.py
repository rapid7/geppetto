import apt_shared
import argparse
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-tf", "--targetFile", help="Override target section")
    parser.add_argument("-mh", "--msfHostsFile", help="Override MSF_HOSTS section")
    parser.add_argument("-v", "--verbose", help="Echo test result to console", action="store_true")
    parser.add_argument("-vf", "--verboseFilename", help="Echo report filename to console", action="store_true")
    parser.add_argument("-f", "--framework", help="Framework branch to use (Overrides testfile)")
    parser.add_argument("-m", "--module", help="Module to use")
    parser.add_argument("-t", "--targetName", help="Target CPE/OS/NAME to use (Overrides testfile)")
    parser.add_argument("-p", "--payload", help="Meterpreter payload to use")
    parser.add_argument("-po", "--payloadOptions", help="Comma delineated venom-style settings for the given payload: attribute=x,attribute2=y...")
    parser.add_argument("testfile", help="json test file to use")
    args = parser.parse_args()

    # REMOVED credential processing from prepConfig, now performed during convertAbstractTarget and confirmMsfHosts
    configData = apt_shared.prepConfig(args)

    """
    PROCESS TARGETS INTO KNOWN VMS
    """
    configData['TARGETS'] = apt_shared.convertAbstractTargets(configData['TARGETS'], configData['CREDS_FILE'], configData['LOG_FILE'])
    configData['MSF_HOSTS'] = apt_shared.confirmMsfHosts(configData['MSF_HOSTS'], configData['CREDS_FILE'], configData['LOG_FILE'])
    if type(configData['TARGETS']) == bool:
        print("NO TARGETS FOUND IN CATALOG")
        exit(999)
    if type(configData['MSF_HOSTS']) == bool:
        print("NO MSF_HOSTS FOUND IN CATALOG")
        exit(999)

    """
    IF GLOBAL PAYLOADS OR MODULES ARE LISTED, FILTER THEM AS BEST WE CAN AND ADD THEM TO EACH TARGET
    NB: I THINK USING GLOBAL EXPLOITS IS A TERRIBLE IDEA, BUT I AM AN ENABLER
    """
    apt_shared.expandPayloadsAndModules(configData)
     
    # portValue TRACKS PORTS SO WE DO NOT REUSE A PORT AND CAUSE A PROBLEM
    portNum = apt_shared.portValue(configData['STARTING_LISTENER'])
    # REPLACE 'UNIQUE_PORT' WILDCARD WITH AN ACTUAL UNIQUE PORT
    apt_shared.replacePortKeywords(configData, portNum)
    
    # DEBUG PRINT
    for target in configData['TARGETS']:
        if 'PAYLOADS' in target:
            apt_shared.logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
        apt_shared.logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))

    """
    NOW EACH HOST HAS A LIST OF ALL THE MODULES AND (POSSIBLY) PAYLOADS IT NEEDS TO USE...... 
    ASSEMBLE EXPLOITS AND PAYLOADS OR JUST MODULES THEM TO FORM VOLTRON..... I MEAN, SESSION_DATA
    TO HELP TRACK THE ACTUAL SESSIONS ESTABLISHED (IF ANY)
    """
    if not apt_shared.setupSessionData(configData):
        apt_shared.bailSafely(configData)

    # DEBUG PRINT
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
    if 'SUCCESS_LIST' in configData:
        apt_shared.expandGlobalList(configData['TARGETS'], configData['SUCCESS_LIST'], "SUCCESS_LIST")
    if 'FAILURE_LIST' in configData:
        apt_shared.expandGlobalList(configData['TARGETS'], configData['FAILURE_LIST'], "FAILURE_LIST")
            
    
    # DEBUG PRINT
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
    if apt_shared.resetVms(configData):
        apt_shared.logMsg(configData['LOG_FILE'], "SUCCESSFULLY RESET VMS")
    else:
        apt_shared.logMsg(configData['LOG_FILE'], "THERE WAS A PROBLEM RESETTING VMS")
    
    """
    WAIT A COUPLE SECONDS TO MAKE SURE WVERYTHING COMPLETES, THEN RETURN THE PROPER VALUE
    """
    apt_shared.logMsg(configData['LOG_FILE'], "WAITING FOR ALL TASKS TO COMPLETE")
    time.sleep(5)
    if args.verboseFilename:
        print("REPORT_LOCATION: " + configData['REPORT_DIR'] + "/" + configData['REPORT_PREFIX'] + ".html")
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
