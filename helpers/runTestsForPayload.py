##############################################################
#
# THIS IS A WRAPPER SCRIPT FOR autoPayloadTest.py
# IT TAKES IN A TEST FILE WITH PAYLOADS AND RUNS THEM
# INDIVIDUALLY AGAINST A COMMON CONFIG FILE
# RUN THIS IN THE SAME FOLDER AS autopayloadTtest.py
#
#############################################################

import argparse
import subprocess
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="Echo test result to console", action="store_true")
    parser.add_argument("-f", "--framework", help="Framework branch to use (Overrides testfile)")
    parser.add_argument("-m", "--module", help="Module to use")
    parser.add_argument("-ss", "--skipSnapshotting", help="Skip intial snapshot and restore (trashes current VM state and leaves VMs on)", action="store_true")
    parser.add_argument("testfile", help="json payload file to use")
    args = parser.parse_args()

    testFilename = args.testfile.strip()

    try:
        payloadFileObj = open(testFilename, 'r')
        jsonStr = payloadFileObj.read()
        payloadFileObj.close()
    except IOError as e:
        print("FAILED TO OPEN OR READ" + testFilename + "\n" + str(e))
    try:
        payloadList = json.loads(jsonStr)
    except ValueError as f:
        print("FAILED TO PARSE JSON FILE " + testFilename + "\n" + str(f))

    if args.framework != None:
        frameworkOption = " -f " + args.framework
    else:
        frameworkOption = ""

    if args.module != None:
        moduleOption = " -m " + args.module
    else:
        moduleOption = ""

    if args.verbose != None:
        verboseOption = " -v "
    else:
        verboseOption = ""

    if args.skipSnapshotting != None:
        skipSnapshottingOption = " -ss "
    else:
        skipSnapshottingOption = ""

    nightlyTestFile = 'public_configs/nightly_tests.json'
    nightlyConfigs = None
    try:
        fileObj = open(nightlyTestFile, 'r')
        jsonStr = fileObj.read()
        fileObj.close()
    except IOError as e:
        print("FAILED TO OPEN OR READ" + nightlyTestFile + "\n" + str(e))
    try:
        nightlyConfigs = json.loads(jsonStr)
    except ValueError as f:
        print("FAILED TO PARSE JSON FILE " + nightlyTestFile + "\n" + str(f))

    cmdList = []
    for config in nightlyConfigs:
        if testFilename in config['payload_files']:
            for payload in payloadList:
                cmdString = "python autoPayloadTest.py -p " + payload['name'].strip() + " " + config['test_config']
                if len(payload['opts']) > 0:
                    cmdString += " -po "
                    for option in payload['opts']:
                        cmdString += option + ","
                cmdString += frameworkOption
                cmdString += moduleOption
                cmdString += verboseOption
                cmdString += skipSnapshottingOption
                cmdList.append(cmdString)

    failures = 0
    for cmd in cmdList:
        print cmd
        if subprocess.call(cmd.split()) == 0:
            print("PASSED")
        else:
            failures += 1
            print("FAILED")
    if failures > 0:
        exit(1)
    
if __name__ == "__main__":
    main()
